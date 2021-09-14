<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SharingGroupFixture;
use \Helper\Fixture\Data\UserFixture;

class ViewSharingGroupCest
{

    private const URL = '/sharing_groups/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $sharingGroupId = 1;
        $I->sendGet(sprintf(self::URL, $sharingGroupId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedSharingGroup(ApiTester $I): void
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

        $I->sendGet(sprintf(self::URL, $sharingGroupId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['SharingGroup' => $fakeSharingGroup->toResponse()]);
    }
}
