<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class IndexUsersCest
{

    private const URL = '/admin/users';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedUser(ApiTester $I): void
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

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([['User' => $fakeUser->toResponse()]]);
    }
}
