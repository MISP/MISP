<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Fixture\SharingGroupsFixture;
use App\Test\Helper\ApiTestTrait;

class ViewSharingGroupApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/view';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.SharingGroups',
        'app.SharingGroupOrgs',
        'app.SharingGroupServers',
    ];

    public function testViewSharingGroupById(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $url = sprintf('%s/%d', self::ENDPOINT, SharingGroupsFixture::SHARING_GROUP_A_ID);
        $this->get($url);

        $this->assertResponseOk();
        $sharingGroup = $this->getJsonResponseAsArray();

        $this->assertEquals(SharingGroupsFixture::SHARING_GROUP_A_ID, $sharingGroup['id']);
        $this->assertEquals(SharingGroupsFixture::SHARING_GROUP_A_UUID, $sharingGroup['uuid']);

        // check that the sharing group contains the correct organisations
        $this->assertArrayHasKey('SharingGroupOrg', $sharingGroup);
        $this->assertCount(2, $sharingGroup['SharingGroupOrg']);
        $this->assertEquals(OrganisationsFixture::ORGANISATION_A_ID, $sharingGroup['SharingGroupOrg'][0]['Organisation']['id']);
        $this->assertEquals(OrganisationsFixture::ORGANISATION_A_UUID, $sharingGroup['SharingGroupOrg'][0]['Organisation']['uuid']);
        $this->assertEquals(OrganisationsFixture::ORGANISATION_B_ID, $sharingGroup['SharingGroupOrg'][1]['Organisation']['id']);
        $this->assertEquals(OrganisationsFixture::ORGANISATION_B_UUID, $sharingGroup['SharingGroupOrg'][1]['Organisation']['uuid']);

        // check that the sharing group contains the correct servers
        $this->assertArrayHasKey('SharingGroupServer', $sharingGroup);
        $this->assertCount(1, $sharingGroup['SharingGroupServer']);
        $this->assertEquals(ServersFixture::SERVER_A_ID, $sharingGroup['SharingGroupServer'][0]['Server']['id']);
        $this->assertEquals(ServersFixture::SERVER_A_NAME, $sharingGroup['SharingGroupServer'][0]['Server']['name']);
    }
}
