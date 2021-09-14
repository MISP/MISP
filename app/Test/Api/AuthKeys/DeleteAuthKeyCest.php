<?php

declare(strict_types=1);

use Helper\Fixture\Data\AuthKeyFixture;

class DeleteAuthKeyCest
{

    private const URL = '/auth_keys/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $authKeyId = 1;
        $I->sendDelete(sprintf(self::URL, $authKeyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDeleteAuthKey(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $authKeyId = 10;

        $I->haveAuthorizationKey($orgId, $userId);

        $fakeAuthKey = AuthKeyFixture::fake(['id' => $authKeyId]);
        $I->haveInDatabase('auth_keys', $fakeAuthKey->toDatabase());

        $I->sendDelete(sprintf(self::URL, $authKeyId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([
            "saved" => true,
            "success" => true,
            "name" => "AuthKey deleted.",
            "message" => "AuthKey deleted.",
            "url" => sprintf(self::URL, $authKeyId)
        ]);
        $I->cantSeeInDatabase('auth_keys', ['id' => $authKeyId]);
    }
}
