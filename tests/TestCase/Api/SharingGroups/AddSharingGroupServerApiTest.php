<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Fixture\SharingGroupsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddSharingGroupServerApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/add-server';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.SharingGroups',
        'app.SharingGroupOrgs',
        'app.SharingGroupServers',
    ];

    public function testAddSharingGroupServer(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->post(
            sprintf("%s/%s/%s", self::ENDPOINT, SharingGroupsFixture::SHARING_GROUP_A_ID, ServersFixture::SERVER_B_ID)
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'SharingGroupServers',
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'server_id' => ServersFixture::SERVER_B_ID
            ]
        );
    }
}
