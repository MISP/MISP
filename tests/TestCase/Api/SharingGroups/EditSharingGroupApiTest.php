<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\SharingGroups;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use App\Test\Fixture\EventBlocklistsFixture;
use App\Test\Fixture\SharingGroupsFixture;

class EditSharingGroupApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/sharing-groups/edit';

    protected $fixtures = [
        'app.Organisations',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
        'app.SharingGroups',
        'app.SharingGroupOrgs',
        'app.SharingGroupServers',
    ];

    public function testEditSharingGroup(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $new_name = "Edited Sharing Group";
        $url = sprintf('%s/%s', self::ENDPOINT, SharingGroupsFixture::SHARING_GROUP_A_UUID);

        $this->post(
            $url,
            [
                'name' => $new_name,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('SharingGroups', [
            'uuid' => SharingGroupsFixture::SHARING_GROUP_A_UUID,
            'name' => $new_name,
        ]);
    }
}
