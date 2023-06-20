<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\SharingGroupsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddSharingGroupOrgApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/add-org';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.SharingGroups',
        'app.SharingGroupOrgs',
        'app.SharingGroupServers',
    ];

    public function testAddSharingGroupOrganisation(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->post(
            sprintf("%s/%s/%s", self::ENDPOINT, SharingGroupsFixture::SHARING_GROUP_A_ID, OrganisationsFixture::ORGANISATION_C_ID)
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'SharingGroupOrgs',
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_C_ID
            ]
        );
    }
}
