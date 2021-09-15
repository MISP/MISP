<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserSettingFixture;
use \Helper\Fixture\Data\UserFixture;

class GetUserSettingByNameCest
{

    private const URL = '/user_settings/getSetting/%s/%s';

    public function testGetSettingReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $userId = 1;
        $userSettingName = 'homepage';
        $I->sendGet(sprintf(self::URL, $userId, $userSettingName));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testGetSettingReturnsExpectedUserSetting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $userSettingName = 'homepage';
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUserSetting = UserSettingFixture::fake([
            'setting' => $userSettingName,
            'user_id' => (string)$userId,
            'value' => [
                'path' => '/attributes/index'
            ]
        ]);
        $I->haveInDatabase('user_settings', $fakeUserSetting->toDatabase());

        $I->sendGet(sprintf(self::URL, $userId, $userSettingName));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson($fakeUserSetting->toResponse()['value']);
    }
}
