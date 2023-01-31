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

    protected const ENDPOINT = '/sharingGroups/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.SharingGroups'
    ];

    public function testIndexSharingGroups(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"id": %d', SharingGroupsFixture::SHARING_GROUP_A_ID));
        $this->assertResponseContains(sprintf('"id": %d', SharingGroupsFixture::SHARING_GROUP_B_ID));
    }
}
