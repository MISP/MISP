<?php

declare(strict_types=1);

namespace App\Test\TestCase\Controller\Users;

use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ControllerTestTrait;
use Cake\TestSuite\TestCase;

class UsersControllerTest extends TestCase
{
    use ControllerTestTrait;

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.Roles',
    ];

    public function testLogin(): void
    {
        $this->enableCsrfToken();
        $this->enableSecurityToken();

        $this->post(
            '/users/login',
            [
                'email' => UsersFixture::USER_ADMIN_EMAIL,
                'password' => UsersFixture::USER_ADMIN_PASSWORD,
            ]
        );

        $this->assertSessionHasKey('authUser.id');
    }
}
