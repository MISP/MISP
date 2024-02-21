<?php
declare(strict_types=1);

namespace App\Test\TestCase\Api\Organisations;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexOrganisationsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/organisations/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
    ];

    public function testIndexOrganisationsAsUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"uuid": "%s"', OrganisationsFixture::ORGANISATION_A_UUID));
        $this->assertResponseContains(sprintf('"uuid": "%s"', OrganisationsFixture::ORGANISATION_B_UUID));
    }

    public function testIndexOrganisationsAsAdmin(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"uuid": "%s"', OrganisationsFixture::ORGANISATION_A_UUID));
        $this->assertResponseContains(sprintf('"uuid": "%s"', OrganisationsFixture::ORGANISATION_B_UUID));
    }

    public function testIndexOrganisationsWithInvalidAuthToken(): void
    {
        $this->setAuthToken('invalid_token');
        $this->get(self::ENDPOINT);
        $this->assertResponseCode(405);
    }

    public function testIndexOrganisationsWithNoAuthToken(): void
    {
        $this->skipOpenApiValidations();
        $this->get(self::ENDPOINT);
        $this->assertResponseCode(405);
    }
}
