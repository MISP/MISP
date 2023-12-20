<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewUserApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/users/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testViewMyUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"email": "%s"', UsersFixture::USER_ADMIN_EMAIL));
    }

    public function testViewUserById(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, UsersFixture::USER_REGULAR_USER_ID);
        $this->get($url);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"email": "%s"', UsersFixture::USER_REGULAR_USER_EMAIL));
    }
}
