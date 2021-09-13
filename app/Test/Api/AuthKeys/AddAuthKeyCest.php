<?php

declare(strict_types=1);

use Helper\Fixture\Data\AuthKeyFixture;

class AddAuthKeyCest
{

    private const URL = '/auth_keys/add/%s';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userId = 1;
        $I->sendPost(sprintf(self::URL, $userId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAddAuthKey(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $authKeyUuid = 'd10d7f80-f457-4013-89a4-3cb0e18c1a50';

        $I->haveAuthorizationKey($orgId, $userId);

        $fakeAuthKey = AuthKeyFixture::fake(['uuid' => $authKeyUuid]);

        $I->sendPost(
            sprintf(self::URL, $userId),
            $fakeAuthKey->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'AuthKey' => [
                    'uuid' => $authKeyUuid,
                    'user_id' => (string)$userId
                ]
            ]
        );
        $I->haveInDatabase('auth_keys', $fakeAuthKey->toDatabase());
    }
}
