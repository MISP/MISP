<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserSettingFixture;
use \Helper\Fixture\Data\UserFixture;

class ViewUserSettingCest
{

    private const URL = '/user_settings/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userSettingId = 1;
        $I->sendGet(sprintf(self::URL, $userSettingId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedUserSetting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $userSettingId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUserSetting = UserSettingFixture::fake(['id' => $userSettingId]);
        $I->haveInDatabase('user_settings', $fakeUserSetting->toDatabase());

        $I->sendGet(sprintf(self::URL, $userSettingId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'UserSetting' => $fakeUserSetting->toResponse()
            ]
        );
    }
}
