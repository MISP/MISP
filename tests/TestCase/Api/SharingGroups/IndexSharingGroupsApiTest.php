<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\SharingGroupsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

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
        $sharingGroups = $this->getJsonResponseAsArray()['response'];

        $this->assertResponseOk();

        $this->assertCount(2, $sharingGroups);
        $this->assertEquals('Sharing Group A', $sharingGroups[0]['name']);
        $this->assertEquals(SharingGroupsFixture::SHARING_GROUP_A_UUID, $sharingGroups[0]['uuid']);
        $this->assertEquals('Sharing Group B', $sharingGroups[1]['name']);
        $this->assertEquals(SharingGroupsFixture::SHARING_GROUP_B_UUID, $sharingGroups[1]['uuid']);
    }
}
