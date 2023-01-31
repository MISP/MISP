<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Organisations;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;

class DeleteOrganisationApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/organisations/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testDeleteOrganisation(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, OrganisationsFixture::ORGANISATION_B_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Organisations', ['id' => OrganisationsFixture::ORGANISATION_B_ID]);
    }

    public function testDeleteOrganisationNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, OrganisationsFixture::ORGANISATION_B_ID);
        $this->delete($url);

        $this->assertResponseCode(405);
        $this->assertDbRecordExists('Organisations', ['id' => OrganisationsFixture::ORGANISATION_B_ID]);
    }
}
