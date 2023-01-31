<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\EncryptionKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\EncryptionKeysFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Helper\ApiTestTrait;

class AddEncryptionKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/encryptionKeys/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.EncryptionKeys'
    ];

    public function testAddUserEncryptionKey(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'type' => EncryptionKeysFixture::TYPE_PGP,
                'encryption_key' => EncryptionKeysFixture::getPublicKey(EncryptionKeysFixture::KEY_TYPE_EDCH),
                'revoked' => false,
                'expires' => null,
                'owner_id' => UsersFixture::USER_ADMIN_ID,
                'owner_model' => 'User'
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"uuid": "%s"', $uuid));
        $this->assertDbRecordExists('EncryptionKeys', ['uuid' => $uuid]);
    }

    public function testAddAdminUserEncryptionKeyNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'type' => EncryptionKeysFixture::TYPE_PGP,
                'encryption_key' => EncryptionKeysFixture::getPublicKey(EncryptionKeysFixture::KEY_TYPE_EDCH),
                'revoked' => false,
                'expires' => null,
                'owner_id' => UsersFixture::USER_ADMIN_ID,
                'owner_model' => 'User'
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('EncryptionKeys', ['uuid' => $uuid]);
    }
}
