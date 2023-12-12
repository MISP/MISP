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

    /**
     * @dataProvider userDataProvider
     */
    public function testAddSharingGroup($user): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken($user['authkey']);

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

        $this->assertResponseCode($user['expectedStatusCode']);

        if ($user['expectedStatusCode'] != 200) {
            return;
        }

        $this->assertDbRecordExists(
            'SharingGroups',
            [
                'uuid' => $uuid,
                'name' => 'Test Sharing Group',
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID
            ]
        );
    }

    /**
     * @dataProvider userDataProvider
     */
    public function testAddSharingGroupOrganisation($user): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken($user['authkey']);

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

        $this->assertResponseCode($user['expectedStatusCode']);

        if ($user['expectedStatusCode'] != 200) {
            return;
        }

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

    /**
     * @dataProvider userDataProvider
     */
    public function testAddSharingGroupServer($user): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken($user['authkey']);

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


        $this->assertResponseCode($user['expectedStatusCode']);

        if ($user['expectedStatusCode'] != 200) {
            return;
        }

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

    public function allowedUserDataProvider(): array
    {
        return [];
    }

    public function userDataProvider(): array
    {
        return [
            [
                [
                    'role' => 'Admin',
                    'authkey' => AuthKeysFixture::ADMIN_API_KEY,
                    'expectedStatusCode' => 200
                ]
            ],
            [
                [
                    'role' => 'Org Admin',
                    'authkey' => AuthKeysFixture::ORG_ADMIN_API_KEY,
                    'expectedStatusCode' => 403
                ]
            ],
            [
                [
                    'role' => 'Sync User',
                    'authkey' => AuthKeysFixture::SYNC_API_KEY,
                    'expectedStatusCode' => 403
                ]
            ],
            [
                [
                    'role' => 'Regular User',
                    'authkey' => AuthKeysFixture::REGULAR_USER_API_KEY,
                    'expectedStatusCode' => 405
                ]
            ]
        ];
    }
}
