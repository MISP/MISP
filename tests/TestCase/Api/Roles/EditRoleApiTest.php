<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Roles;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\RolesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class EditRoleApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/roles/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
    ];

    public function testEditRoles(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, RolesFixture::ROLE_SYNC_ID);
        $this->put(
            $url,
            [
                'perm_template' => true,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'Roles',
            [
                'id' => RolesFixture::ROLE_SYNC_ID,
                'perm_template' => true
            ]
        );
    }

    public function testEditRoleNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, RolesFixture::ROLE_REGULAR_USER_ID);
        $this->put(
            $url,
            [
                'perm_admin' => true,
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists(
            'Roles',
            [
                'id' => RolesFixture::ROLE_REGULAR_USER_ID,
                'perm_admin' => true
            ]
        );
    }
}
