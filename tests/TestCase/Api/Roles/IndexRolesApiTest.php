<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Roles;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class IndexRolesApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/roles/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Roles'
    ];

    public function testIndexRoles(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $roles = $this->getJsonResponseAsArray();
        $this->assertCount(6, $roles);

        $this->assertEquals('admin', $roles[0]['name']);
        $this->assertEquals('Org Admin', $roles[1]['name']);
        $this->assertEquals('User', $roles[2]['name']);
        $this->assertEquals('Publisher', $roles[3]['name']);
        $this->assertEquals('Sync user', $roles[4]['name']);
        $this->assertEquals('Read Only', $roles[5]['name']);
    }
}
