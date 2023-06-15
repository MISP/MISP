<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\SharingGroupsFixture;
use App\Test\Helper\ApiTestTrait;

class IndexSharingGroupsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.SharingGroups',
        'app.SharingGroupOrgs',
        'app.SharingGroupServers',
    ];

    public function testIndexSharingGroups(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"uuid": "%s"', SharingGroupsFixture::SHARING_GROUP_A_UUID));
        $this->assertResponseContains(sprintf('"uuid": "%s"', SharingGroupsFixture::SHARING_GROUP_B_UUID));
    }
}
