<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuthKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class ViewAuthKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/auth-keys/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testViewAuthKeyById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, AuthKeysFixture::REGULAR_USER_API_ID);
        $this->get($url);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"authkey_start": "%s"', substr(AuthKeysFixture::REGULAR_USER_API_KEY, 0, 4)));
    }
}
