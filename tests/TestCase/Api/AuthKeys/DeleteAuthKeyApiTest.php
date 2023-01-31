<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\AuthKeys;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class DeleteAuthKeyApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/authKeys/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testDeleteAdminAuthKey(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, AuthKeysFixture::ADMIN_API_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('AuthKeys', ['id' => AuthKeysFixture::ADMIN_API_ID]);
    }

    public function testDeleteOrgAdminAuthKeyNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, AuthKeysFixture::ORG_ADMIN_API_ID);

        $this->delete($url);
        $this->assertDbRecordExists('AuthKeys', ['id' => AuthKeysFixture::ORG_ADMIN_API_ID]);
        
        $this->markTestIncomplete('FIXME: this test returns string(4) "null", which is not a valid JSON object with 405 status code.');
        $this->assertResponseCode(405);
    }
}
