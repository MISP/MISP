<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\SharingGroupsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class RemoveSharingGroupOrgApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/remove-org';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.SharingGroups',
        'app.SharingGroupOrgs',
        'app.SharingGroupServers',
    ];

    public function testRemoveSharingGroupOrganisation(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->assertDbRecordExists(
            'SharingGroupOrgs',
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_B_ID
            ]
        );

        $this->post(
            sprintf("%s/%s/%s", self::ENDPOINT, SharingGroupsFixture::SHARING_GROUP_A_ID, OrganisationsFixture::ORGANISATION_B_ID)
        );

        $this->assertResponseOk();
        $this->assertDbRecordNotExists(
            'SharingGroupOrgs',
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_B_ID
            ]
        );
    }
}
