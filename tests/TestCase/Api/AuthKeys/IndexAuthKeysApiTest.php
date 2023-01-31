<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuthKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class IndexAuthKeysApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/authKeys/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testIndexAuthKeys(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', AuthKeysFixture::ADMIN_API_ID));
    }

    public function testIndexDoesNotShowAdminAuthKeysAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseNotContains(sprintf('"id": %d', AuthKeysFixture::REGULAR_USER_API_KEY));
    }
}
