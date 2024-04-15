<?php
declare(strict_types=1);

namespace App\Test\TestCase\Api\Organisations;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class EditOrganisationsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/organisations/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
    ];

    private function editOrganisation(int $org_id): void
    {
        $url = sprintf('%s/%d', self::ENDPOINT, $org_id);
        $this->put(
            $url,
            [
                'id' => $org_id,
                'description' => 'new description',
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'Organisations',
            [
                'id' => $org_id,
                'description' => 'new description',
            ]
        );
    }

    private function editNotAllowed(int $org_id): void
    {
        $url = sprintf('%s/%d', self::ENDPOINT, $org_id);
        $this->put(
            $url,
            [
                'id' => $org_id,
                'description' => 'new description',
            ]
        );
        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists(
            'Organisations',
            [
                'id' => $org_id,
                'description' => 'new description',
            ]
        );
    }

    public function testEditOrganisationAsAdmin(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->editOrganisation(OrganisationsFixture::ORGANISATION_A_ID);
    }

    public function testEditOrganisationAsOrgAdmin(): void
    {
        $this->setAuthToken(AuthKeysFixture::ORG_ADMIN_API_KEY); // user from org A
        $this->editOrganisation(OrganisationsFixture::ORGANISATION_A_ID);
    }

    public function testEditNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $this->editNotAllowed(OrganisationsFixture::ORGANISATION_A_ID);
    }

    public function testEditNotAllowedAsWrongOrgAdmin(): void
    {
        $this->setAuthToken(AuthKeysFixture::ORG_ADMIN_API_KEY); // user from org A
        $this->editNotAllowed(OrganisationsFixture::ORGANISATION_B_ID); // edit org B not allowed
    }

    public function testEditNameAlreadyExists(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, OrganisationsFixture::ORGANISATION_A_ID);
        $this->put(
            $url,
            [
                'id' => OrganisationsFixture::ORGANISATION_A_ID,
                'name' => 'Organisation B',
            ]
        );
        $this->assertResponseCode(200);
        $this->assertDbRecordNotExists(
            'Organisations',
            [
                'id' => OrganisationsFixture::ORGANISATION_A_ID,
                'description' => 'Organisation B',
            ]
        );
    }
}
