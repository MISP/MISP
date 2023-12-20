<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuthKeys;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddAuthKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/auth-keys/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testAddAuthKey(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->post(
            self::ENDPOINT,
            [
                'comment' => 'test auth key',
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('AuthKeys', ['comment' => 'test auth key']);
    }
}
