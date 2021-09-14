<?php

declare(strict_types=1);

use Helper\Fixture\Data\AuthKeyFixture;

class EditAuthKeyCest
{

    private const URL = '/auth_keys/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $authKeyId = 1;
        $I->sendPost(sprintf(self::URL, $authKeyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEditAuthKey(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $authKeyId = 10;

        $I->haveAuthorizationKey($orgId, $userId);

        $fakeAuthKey = AuthKeyFixture::fake(
            [
                'id' => $authKeyId,
                'user_id' => $userId,
                'read_only' => false
            ]
        );
        $I->haveInDatabase('auth_keys', $fakeAuthKey->toDatabase());

        $I->sendPost(
            sprintf(self::URL, $authKeyId),
            [
                'read_only' => true
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([
            'AuthKey' => [
                'id' => $authKeyId,
                'read_only' => true
            ]
        ]);
        $I->seeInDatabase('auth_keys', [
            'id' => $authKeyId,
            'read_only' => true
        ]);
    }
}
