<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserSettingFixture;
use \Helper\Fixture\Data\UserFixture;

class SetUserSettingCest
{

    private const URL = '/user_settings/setSetting/%s/%s';

    public function testSetSettingReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userId = 1;
        $settingName = 'homepage';
        $I->sendPost(sprintf(self::URL, $userId, $settingName));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testSetUserSetting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $settingName = 'homepage';
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUserSetting = UserSettingFixture::fake([
            'setting' => $settingName,
            'user_id' => (string)$userId,
            'value' => [
                'path' => '/attributes/index'
            ]
        ]);

        $I->sendPost(sprintf(self::URL, $userId, $settingName), $fakeUserSetting->toRequest());

        $fakeUserSetting->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..UserSetting.id')[0],
            'timestamp' => $I->grabDataFromResponseByJsonPath('$..UserSetting.timestamp')[0],
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'UserSetting' => $fakeUserSetting->toResponse()
            ]
        );
        $I->seeInDatabase('user_settings', $fakeUserSetting->toDatabase());
    }
}
