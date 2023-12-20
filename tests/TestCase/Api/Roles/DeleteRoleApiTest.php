<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\RolesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteRoleApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/roles/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
    ];

    public function testDeleteRole(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, RolesFixture::ROLE_READ_ONLY_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Roles', ['id' => RolesFixture::ROLE_READ_ONLY_ID]);
    }

    public function testDeleteUserNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, RolesFixture::ROLE_READ_ONLY_ID);
        $this->delete($url);

        $this->assertResponseCode(405);
        $this->assertDbRecordExists('Roles', ['id' => RolesFixture::ROLE_READ_ONLY_ID]);
    }
}
