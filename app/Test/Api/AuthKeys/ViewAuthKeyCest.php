<?php

declare(strict_types=1);

use Helper\Fixture\Data\AuthKeyFixture;

class ViewAuthKeyCest
{

    private const URL = '/auth_keys/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $authKeyId = 1;
        $I->sendGet(sprintf(self::URL, $authKeyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedAuthKey(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $authKeyId = 10;

        $I->haveAuthorizationKey($orgId, $userId);

        $fakeAuthKey = AuthKeyFixture::fake(['id' => $authKeyId]);
        $I->haveInDatabase('auth_keys', $fakeAuthKey->toDatabase());

        $I->sendGet(sprintf(self::URL, $authKeyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([
            'AuthKey' => [
                'id' => $authKeyId,
            ]
        ]);
    }
}
