<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Fixture\SharingGroupsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class RemoveSharingGroupServerApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/remove-server';

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

    public function testRemoveSharingGroupServer(): void
    {
        $this->skipOpenApiValidations();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->assertDbRecordExists(
            'SharingGroupServers',
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'server_id' => ServersFixture::SERVER_C_ID
            ]
        );

        $this->post(
            sprintf("%s/%s/%s", self::ENDPOINT, SharingGroupsFixture::SHARING_GROUP_A_ID, ServersFixture::SERVER_C_ID)
        );

        $this->assertResponseOk();
        $this->assertDbRecordNotExists(
            'SharingGroupServers',
            [
                'sharing_group_id' => SharingGroupsFixture::SHARING_GROUP_A_ID,
                'server_id' => ServersFixture::SERVER_C_ID
            ]
        );
    }
}
