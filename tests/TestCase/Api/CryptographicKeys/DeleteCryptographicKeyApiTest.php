<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\CryptographicKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\CryptographicKeysFixture;
use App\Test\Helper\ApiTestTrait;

class DeleteCryptographicKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/cryptographic-keys/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.CryptoGraphicKeys'
    ];

    public function testDeleteCryptographicKeyByUUID(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, CryptographicKeysFixture::CRYPTOGRAPHIC_KEY_REGULAR_USER_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('CryptographicKeys', ['uuid' => CryptographicKeysFixture::CRYPTOGRAPHIC_KEY_REGULAR_USER_UUID]);
    }

    public function testDeleteCryptographicKeyById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, CryptographicKeysFixture::CRYPTOGRAPHIC_KEY_REGULAR_USER_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('CryptographicKeys', ['uuid' => CryptographicKeysFixture::CRYPTOGRAPHIC_KEY_REGULAR_USER_UUID]);
    }
}
