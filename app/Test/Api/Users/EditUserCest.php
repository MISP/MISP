<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class EditUserCest
{

    private const URL = '/admin/users/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userId = 1;
        $I->sendPut(sprintf(self::URL, $userId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEdit(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $fakeUserId = 2;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUser = UserFixture::fake(
            [
                'id' => (string)$fakeUserId,
                'org_id' => (string)$orgId,
                'role_id' => (string)UserFixture::ROLE_USER,
            ]
        );
        $I->haveInDatabase('users', $fakeUser->toDatabase());

        $fakeUser->set(
            [
                'email' => 'foo@bar.com',
                'role_id' => (string)UserFixture::ROLE_ADMIN
            ]
        );

        $I->sendPut(sprintf(self::URL, $fakeUserId), $fakeUser->toRequest());

        $fakeUser->set([
            'date_modified' => $I->grabDataFromResponseByJsonPath('$..User.date_modified')[0],
            'date_created' => $I->grabDataFromResponseByJsonPath('$..User.date_created')[0],
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['User' => $fakeUser->toResponse()]);
        $I->seeInDatabase('users', $fakeUser->toDatabase());
    }
}
