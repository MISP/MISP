<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SharingGroupFixture;
use \Helper\Fixture\Data\UserFixture;

class IndexSharingGroupsCest
{

    private const URL = '/sharing_groups';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedSharingGroup(ApiTester $I): void
    {
        $orgId = 1;
        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);

        $sharingGroupId = 1;
        $fakeSharingGroup = SharingGroupFixture::fake(
            [
                'id' => (string)$sharingGroupId,
                'org_id' => (string)$orgId
            ]
        );
        $I->haveInDatabase('sharing_groups', $fakeSharingGroup->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'response' => [
                    [
                        'SharingGroup' => $fakeSharingGroup->toResponse()
                    ]
                ]
            ]
        );
    }
}
