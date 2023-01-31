<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\EncryptionKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EncryptionKeysFixture;
use App\Test\Helper\ApiTestTrait;

class EditEncryptionKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/encryptionKeys/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.EncryptionKeys'
    ];

    public function testRevokeEncryptionKey(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, EncryptionKeysFixture::ENCRYPTION_KEY_ORG_A_ID);
        $this->put(
            $url,
            [
                'revoked' => true,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'EncryptionKeys',
            [
                'id' => EncryptionKeysFixture::ENCRYPTION_KEY_ORG_A_ID,
                'revoked' => true,
            ]
        );
    }

    public function testRevokeAdminEncryptionKeyNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, EncryptionKeysFixture::ENCRYPTION_KEY_ORG_B_ID);
        $this->put(
            $url,
            [
                'revoked' => true
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists(
            'EncryptionKeys',
            [
                'id' => EncryptionKeysFixture::ENCRYPTION_KEY_ORG_B_ID,
                'revoked' => true
            ]
        );
    }
}
