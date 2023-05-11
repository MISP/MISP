<?php

declare(strict_types=1);

namespace App\Test\TestCase\Controller\Users;

use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use App\Test\Fixture\UsersFixture;

class UsersControllerTest extends TestCase
{
    use IntegrationTestTrait;

    protected $fixtures = [
        'app.Users'
    ];
    public function testLogin(): void
    {
        $this->enableCsrfToken();
        $this->enableSecurityToken();

        $this->post('/users/login', [
            'email' => UsersFixture::USER_ADMIN_EMAIL,
            'password' => UsersFixture::USER_ADMIN_PASSWORD,
        ]);

        $this->assertSessionHasKey('authUser.id');
    }
}
