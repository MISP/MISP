<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class EditSettingCest
{

    private const URL = '/servers/serverSettingsEdit/%s';

    public function testEditSettingReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $settingName = 'MISP.background_jobs';
        $I->sendPost(sprintf(self::URL, $settingName));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEditSetting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $settingName = 'MISP.live';
        $I->sendPost(
            sprintf(self::URL, $settingName),
            [
                'value' => true
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Field updated',
                'message' => 'Field updated',
                'url' => '/servers/serverSettingsEdit',
            ]
        );
    }
}
