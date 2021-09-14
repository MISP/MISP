<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SharingGroupFixture;
use \Helper\Fixture\Data\UserFixture;

class AddSharingGroupCest
{

    private const URL = '/sharing_groups/add';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAdd(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $sharingGroupId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $sharingGroupId = 1;
        $fakeSharingGroup = SharingGroupFixture::fake(
            [
                'id' => (string)$sharingGroupId,
                'org_id' => (string)$orgId,
                'sync_user_id' => (string)$userId,
                'local' => false
            ]
        );

        $I->sendPost(self::URL, $fakeSharingGroup->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $fakeSharingGroup->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..SharingGroup.id')[0],
            'created' => $I->grabDataFromResponseByJsonPath('$..SharingGroup.created')[0],
            'modified' => $I->grabDataFromResponseByJsonPath('$..SharingGroup.modified')[0],
        ]);

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['SharingGroup' => $fakeSharingGroup->toResponse()]);
        $I->seeInDatabase('sharing_groups', $fakeSharingGroup->toDatabase());
    }
}
