<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\CryptographicKeys;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CryptographicKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ViewCryptographicKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/cryptographic-keys/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.CryptographicKeys'
    ];

    public function testViewCryptographicKeyById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, CryptographicKeysFixture::CRYPTOGRAPHIC_KEY_REGULAR_USER_ID);
        $this->get($url);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', CryptographicKeysFixture::CRYPTOGRAPHIC_KEY_REGULAR_USER_ID));
    }
}
