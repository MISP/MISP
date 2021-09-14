<?php

declare(strict_types=1);

use Helper\Fixture\Data\AuthKeyFixture;

class IndexAuthKeysCest
{

    private const URL = '/auth_keys';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedAuthKey(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;

        $authKey = $I->haveAuthorizationKey($orgId, $userId);

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([
            [
                'AuthKey' => [
                    'authkey_start' => substr($authKey, 0, 4),
                    'authkey_end' => substr($authKey, -4),
                ]
            ]
        ]);
    }

    public function testIndexSearchReturnsExpectedAuthKey(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $authKeyUuid = 'd10d7f80-f457-4013-89a4-3cb0e18c1a54';

        $I->haveAuthorizationKey($orgId, $userId);

        $fakeAuthKey = AuthKeyFixture::fake(['uuid' => $authKeyUuid]);
        $I->haveInDatabase('auth_keys', $fakeAuthKey->toDatabase());

        $I->sendPost(
            self::URL,
            [
                'uuid' => $authKeyUuid
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([
            [
                'AuthKey' => [
                    'uuid' => $authKeyUuid
                ]
            ]
        ]);
    }
}
