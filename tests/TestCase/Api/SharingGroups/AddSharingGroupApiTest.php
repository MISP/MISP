<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddSharingGroupApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.SharingGroups',
        'app.SharingGroupOrgs',
        'app.SharingGroupServers',
    ];

    public function testAddSharingGroup(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid();

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'name' => 'Test Sharing Group',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'SharingGroups',
            [
                'uuid' => $uuid,
                'name' => 'Test Sharing Group',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID
            ]
        );
    }

    public function testAddSharingGroupOrganisation(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid();

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'name' => 'Test Sharing Group with Organisation',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'SharingGroupOrg' => [
                    [
                        'uuid' => OrganisationsFixture::ORGANISATION_B_UUID,
                        'extend' => false
                    ]
                ]
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'SharingGroups',
            [
                'uuid' => $uuid,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID
            ]
        );
        $this->assertDbRecordExists(
            'SharingGroupOrgs',
            [
                'org_id' => OrganisationsFixture::ORGANISATION_B_ID
            ]
        );
    }

    public function testAddSharingGroupServer(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid();


        $server = $this->getRecordFromDb('Servers', ['id' => OrganisationsFixture::ORGANISATION_B_ID]);

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'name' => 'Test Sharing Group with Server',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'SharingGroupServer' => [
                    [
                        'server_id' => $server['id'],
                        'url' => $server['url'],
                        'all_orgs' => false,
                    ]
                ]
            ]
        );
        $this->assertResponseOk();

        $sharingGroup = $this->getJsonResponseAsArray();

        $this->assertDbRecordExists(
            'SharingGroups',
            [
                'uuid' => $uuid,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID
            ]
        );
        $this->assertDbRecordExists(
            'SharingGroupServers',
            [
                'server_id' => $server['id'],
                'sharing_group_id' => $sharingGroup['id']
            ]
        );
    }
}
