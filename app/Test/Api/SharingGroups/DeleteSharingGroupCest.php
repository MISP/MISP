<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SharingGroupFixture;
use \Helper\Fixture\Data\UserFixture;

class DeleteSharingGroupCest
{

    private const URL = '/sharing_groups/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $sharingGroupId = 1;
        $I->sendDelete(sprintf(self::URL, $sharingGroupId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDelete(ApiTester $I): void
    {
        $orgId = 1;
        $sharingGroupId = 1;
        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);

        $sharingGroupId = 1;
        $fakeSharingGroup = SharingGroupFixture::fake(
            [
                'id' => (string)$sharingGroupId,
                'org_id' => (string)$orgId
            ]
        );
        $I->haveInDatabase('sharing_groups', $fakeSharingGroup->toDatabase());

        $I->sendDelete(sprintf(self::URL, $sharingGroupId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'SharingGroup deleted',
                'message' => 'SharingGroup deleted',
                'url' => sprintf(self::URL, $sharingGroupId),
            ]
        );
        $I->cantSeeInDatabase('sharing_groups', ['id' => $sharingGroupId]);
    }
}
