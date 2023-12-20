<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Roles;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\RolesFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class SetDefaultRoleApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/admin/roles/set_default';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
    ];

    public function testSetDefaultRole(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, RolesFixture::ROLE_REGULAR_USER_ID);
        $this->post($url);

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'AdminSettings',
            [
                'setting' => 'default_role',
                'value' => RolesFixture::ROLE_REGULAR_USER_ID
            ]
        );
    }
}
