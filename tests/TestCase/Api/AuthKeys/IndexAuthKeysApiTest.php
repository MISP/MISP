<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuthKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class IndexAuthKeysApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/auth-keys/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testIndexAuthKeys(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();

        $response = $this->getJsonResponseAsArray();
        $this->assertCount(4, $response);
    }
}
