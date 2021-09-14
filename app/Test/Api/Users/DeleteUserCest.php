<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class DeleteUserCest
{

    private const URL = '/admin/users/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userId = 1;
        $I->sendDelete(sprintf(self::URL, $userId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDelete(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUserId = 2;
        $fakeUser = UserFixture::fake(
            [
                'id' => (string)$fakeUserId,
                'org_id' => (string)$orgId,
                'role_id' => (string)UserFixture::ROLE_USER,
            ]
        );
        $I->haveInDatabase('users', $fakeUser->toDatabase());

        $I->sendDelete(sprintf(self::URL, $fakeUserId), $fakeUser->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'User deleted.',
                'message' => 'User deleted.',
                'url' => sprintf('/admin/users/delete/%s', $fakeUserId)
            ]
        );
        $I->cantSeeInDatabase('users', ['id' => $fakeUserId]);
    }
}
