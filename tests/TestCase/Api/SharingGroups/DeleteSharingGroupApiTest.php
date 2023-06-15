<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use App\Test\Fixture\SharingGroupsFixture;

class DeleteSharingGroupApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.SharingGroups',
        'app.SharingGroupOrgs',
        'app.SharingGroupServers',
    ];

    public function testDeleteSharingGroupByUUID(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, SharingGroupsFixture::SHARING_GROUP_A_UUID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('SharingGroups', ['uuid' => SharingGroupsFixture::SHARING_GROUP_A_UUID]);
    }

    public function testDeleteSharingGroupById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%s', self::ENDPOINT, SharingGroupsFixture::SHARING_GROUP_A_ID);
        $this->delete($url);

        $this->assertResponseOk();
        $this->assertDbRecordNotExists('SharingGroups', ['id' => SharingGroupsFixture::SHARING_GROUP_A_ID]);
    }
}
