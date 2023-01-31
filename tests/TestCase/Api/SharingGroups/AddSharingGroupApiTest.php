<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\UsersFixture;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class AddSharingGroupApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharingGroups/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.SharingGroups'
    ];

    public function testAddSharingGroup(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'name' => 'Test Sharing Group',
                'releasability' => 'Test Sharing Group releasability',
                'description' => 'Test Sharing Group description',
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'active' => true,
                'local' => true
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"uuid": "%s"', $uuid));
        $this->assertDbRecordExists('SharingGroups', ['uuid' => $uuid]);
    }

    public function testAddSharingGroupNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'name' => 'Test Sharing Group',
                'releasability' => 'Sharing Group A',
                'description' => 'Sharing Group A description',
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'active' => true,
                'local' => true
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('SharingGroups', ['uuid' => $uuid]);
    }
}
