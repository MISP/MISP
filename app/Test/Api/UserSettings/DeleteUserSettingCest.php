<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserSettingFixture;
use \Helper\Fixture\Data\UserFixture;

class DeleteUserSettingCest
{

    private const URL = '/user_settings/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userSettingId = 1;
        $I->sendDelete(sprintf(self::URL, $userSettingId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDelete(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $userSettingId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUserSetting = UserSettingFixture::fake(['id' => $userSettingId]);
        $I->haveInDatabase('user_settings', $fakeUserSetting->toDatabase());

        $I->sendDelete(sprintf(self::URL, $userSettingId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => "Setting deleted.",
                'message' => "Setting deleted.",
                'url' => "/user_settings/delete/1"
            ]
        );
        $I->cantSeeInDatabase('user_settings', ['id' => $userSettingId]);
    }
}
