<?php

declare(strict_types=1);

use \Helper\Fixture\Data\ServerFixture;
use \Helper\Fixture\Data\SharingGroupFixture;
use \Helper\Fixture\Data\UserFixture;

class RemoveServerFromSharingGroupCest
{

    private const URL = '/sharing_groups/removeServer/%s/%s';

    public function testRemoveServerFromSharingGroupReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $sharingGroupId = 1;
        $orgId = 1;
        $I->sendPost(sprintf(self::URL, $sharingGroupId, $orgId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testRemoveServerFromSharingGroup(ApiTester $I): void
    {
        $orgId = 1;
        $sharingGroupId = 1;
        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);

        $sharingGroupId = 1;
        $serverId = 1;
        $fakeSharingGroup = SharingGroupFixture::fake(
            [
                'id' => (string)$sharingGroupId,
                'org_id' => (string)$orgId
            ]
        );
        $fakeServer = ServerFixture::fake(['id' => $serverId]);
        $I->haveInDatabase('sharing_groups', $fakeSharingGroup->toDatabase());
        $I->haveInDatabase('servers', $fakeServer->toDatabase());
        $I->haveInDatabase(
            'sharing_group_servers',
            [
                'sharing_group_id' => $sharingGroupId,
                'server_id' => $orgId,
                'all_orgs' => false
            ]
        );

        $I->sendPost(sprintf(self::URL, $sharingGroupId, $serverId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Server removed from the sharing group.',
                'message' => 'Server removed from the sharing group.',
                'url' => '/sharing_groups/removeServer'
            ]
        );
        $I->cantSeeInDatabase(
            'sharing_group_servers',
            [
                'sharing_group_id' => $sharingGroupId,
                'server_id' => $serverId
            ]
        );
    }
}
