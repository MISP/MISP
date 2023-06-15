<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;

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

    public function testSharingGroup(): void
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
}
