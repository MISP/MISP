<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class ViewUserCest
{

    private const URL = '/admin/users/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userId = 1;
        $I->sendGet(sprintf(self::URL, $userId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedUser(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $fakeUser = UserFixture::fake(
            [
                'id' => (string)$userId,
                'org_id' => (string)$orgId,
                'role_id' => (string)UserFixture::ROLE_ADMIN,
            ]
        );

        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN, $fakeUser);

        $I->sendGet(sprintf(self::URL, $userId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['User' => $fakeUser->toResponse()]);
    }
}
