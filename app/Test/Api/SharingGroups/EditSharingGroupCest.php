<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SharingGroupFixture;
use \Helper\Fixture\Data\UserFixture;

class EditSharingGroupCest
{

    private const URL = '/sharing_groups/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $sharingGroupId = 1;
        $I->sendPost(sprintf(self::URL, $sharingGroupId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEdit(ApiTester $I): void
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

        $fakeSharingGroup->set([
            'name' => 'foobar',
        ]);

        $I->sendPost(sprintf(self::URL, $sharingGroupId), $fakeSharingGroup->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $fakeSharingGroup->set([
            'modified' => $I->grabDataFromResponseByJsonPath('$..SharingGroup.modified')[0],
        ]);

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['SharingGroup' => $fakeSharingGroup->toResponse()]);
        $I->seeInDatabase('sharing_groups', $fakeSharingGroup->toDatabase());
    }
}
