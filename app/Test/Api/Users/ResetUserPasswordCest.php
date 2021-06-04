<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class ResetUserPasswordCest
{

    private const URL = '/users/initiatePasswordReset/%s/%s';

    public function testResetUserPasswordReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userId = 1;
        $firstTime = 0;
        $I->sendPost(sprintf(self::URL, $userId, $firstTime));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testResetUserPassword(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUserId = 2;
        $firstTime = 0;
        $fakeUser = UserFixture::fake(
            [
                'id' => (string)$fakeUserId,
                'org_id' => (string)$orgId,
                'role_id' => (string)UserFixture::ROLE_USER,
            ]
        );
        $I->haveInDatabase('users', $fakeUser->toDatabase());

        $I->sendPost(sprintf(self::URL, $fakeUserId, $firstTime));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        // // TODO: Fix email error in docker env
        // $I->seeResponseContainsJson(
        //     [
        //         'saved' => true,
        //         'success' => 'New credentials sent.' 
        //     ]
        // );
    }
}
