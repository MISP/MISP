<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Roles;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\RolesFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewRoleApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/roles/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Roles'
    ];


    public function testViewRoleById(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, RolesFixture::ROLE_ADMIN_ID);
        $this->get($url);

        $this->assertResponseOk();
        $role = $this->getJsonResponseAsArray();
        $this->assertEquals('admin', $role['name']);
        $this->assertEquals(RolesFixture::ROLE_ADMIN_ID, $role['id']);
    }
}
