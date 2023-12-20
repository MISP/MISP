<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddUserApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/users/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testAddUser(): void
    {
        $this->markTestSkipped("This is not implemented yet.");
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->post(
            self::ENDPOINT,
            [
                'individual_id' => UsersFixture::USER_REGULAR_USER_ID,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'role_id' => UsersFixture::ROLE_REGULAR_USER_ID,
                'disabled' => false,
                'username' => 'test',
                'password' => 'Password123456!',
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains('"username": "test"');
        $this->assertDbRecordExists('Users', ['username' => 'test']);
    }

    public function testAddUserNotAllowedAsRegularUser(): void
    {
        $this->markTestSkipped("This is not implemented yet.");
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $this->post(
            self::ENDPOINT,
            [
                'individual_id' => UsersFixture::USER_REGULAR_USER_ID,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'role_id' => UsersFixture::ROLE_REGULAR_USER_ID,
                'disabled' => false,
                'username' => 'test',
                'password' => 'Password123456!'
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('Users', ['username' => 'test']);
    }
}
