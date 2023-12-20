<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Users;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexUsersApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/users/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testIndexUsers(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"email": "%s"', UsersFixture::USER_ADMIN_EMAIL));
    }
}
