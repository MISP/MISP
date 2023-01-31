<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\EncryptionKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EncryptionKeysFixture;
use App\Test\Helper\ApiTestTrait;

class DeleteEncryptionKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/encryptionKeys/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.EncryptionKeys'
    ];

    public function testDeleteEncryptionKey(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, EncryptionKeysFixture::ENCRYPTION_KEY_ORG_A_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('EncryptionKeys', ['id' => EncryptionKeysFixture::ENCRYPTION_KEY_ORG_A_ID]);
    }

    public function testDeleteEncryptionKeyNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, EncryptionKeysFixture::ENCRYPTION_KEY_ORG_B_ID);
        $this->delete($url);

        $this->assertResponseCode(405);
        $this->assertDbRecordExists('EncryptionKeys', ['id' => EncryptionKeysFixture::ENCRYPTION_KEY_ORG_B_ID]);
    }
}
