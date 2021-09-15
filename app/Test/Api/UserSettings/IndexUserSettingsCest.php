<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserSettingFixture;
use \Helper\Fixture\Data\UserFixture;
use \Codeception\Scenario;

class IndexUserSettingsCest
{

    private const URL = '/user_settings';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedUserSetting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeUserSetting = UserSettingFixture::fake();
        $I->haveInDatabase('user_settings', $fakeUserSetting->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                [
                    'UserSetting' => $fakeUserSetting->toResponse()
                ]
            ]
        );
    }

    public function testPostIndexReturnsExpectedUserSetting(ApiTester $I, Scenario $scenario): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $dashboardAccessUserSetting = UserSettingFixture::fake(['setting' => 'dashboard_access', 'value' => 1]);
        $homepageUserSetting = UserSettingFixture::fake([
            'setting' => 'homepage',
            'value' => [
                'path' => '/attributes/index'
            ]
        ]);
        $I->haveInDatabase('user_settings', $dashboardAccessUserSetting->toDatabase());
        $I->haveInDatabase('user_settings', $homepageUserSetting->toDatabase());

        $I->sendPost(self::URL, ['setting' => 'homepage']);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                [
                    'UserSetting' => $homepageUserSetting->toResponse()
                ]
            ]
        );
    }
}
