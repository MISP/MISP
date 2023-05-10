<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ApiTestTrait;

class DeleteUserApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/users/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testDeleteUser(): void
    {
        $this->markTestSkipped("This is not implemented yet.");
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, UsersFixture::USER_REGULAR_USER_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Users', ['id' => UsersFixture::USER_REGULAR_USER_ID]);
    }

    public function testDeleteUserNotAllowedAsRegularUser(): void
    {
        $this->markTestSkipped("This is not implemented yet.");
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, UsersFixture::USER_ORG_ADMIN_ID);
        $this->delete($url);

        $this->assertResponseCode(405);
        $this->assertDbRecordExists('Users', ['id' => UsersFixture::USER_ORG_ADMIN_ID]);
    }
}
