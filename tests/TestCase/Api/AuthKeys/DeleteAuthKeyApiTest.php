<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuthKeys;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteAuthKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/auth-keys/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
    ];

    public function testDeleteAuthKeyById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, AuthKeysFixture::REGULAR_USER_API_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('AuthKeys', ['id' => AuthKeysFixture::REGULAR_USER_API_ID]);
    }
}
