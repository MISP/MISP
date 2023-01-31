<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\EncryptionKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EncryptionKeysFixture;
use App\Test\Helper\ApiTestTrait;

class IndexEncryptionKeysApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/encryptionKeys/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.EncryptionKeys'

    ];

    public function testIndexEncryptionKeys(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', EncryptionKeysFixture::ENCRYPTION_KEY_ORG_A_ID));
    }
}
