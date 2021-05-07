<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class AddUserCest
{

    private const URL = '/admin/users/add';

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
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUser = UserFixture::fake(
            [
                'org_id' => (string)$orgId,
                'role_id' => (string)UserFixture::ROLE_USER,
                'invited_by' => (string)$userId,
                'server_id' => '0'
            ]
        );

        $I->sendPost(self::URL, $fakeUser->toRequest());

        $fakeUserId = $I->grabDataFromResponseByJsonPath('$..User.id')[0];
        $fakeUser->set([
            'id' => $fakeUserId,
            'date_modified' => $I->grabDataFromResponseByJsonPath('$..User.date_modified')[0],
            'date_created' => $I->grabDataFromResponseByJsonPath('$..User.date_created')[0],
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['User' => $fakeUser->toResponse()]);
        $createdUser = $fakeUser->toDatabase();
        unset($createdUser['password']); // password is randomly generated
        $I->seeInDatabase('users', $createdUser);
    }
}
