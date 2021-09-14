<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class GetSettingByNameCest
{

    private const URL = '/servers/getSetting/%s';

    public function testGetWorkersReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $settingName = 'MISP.background_jobs';
        $I->sendGet(sprintf(self::URL, $settingName));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testGetSetting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '1');

        $settingName = 'MISP.background_jobs';
        $I->sendGet(sprintf(self::URL, $settingName));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'level' => 1,
                'description' => 'Enables the use of MISP\'s background processing.',
                'value' => true,
                'errorMessage' => '',
                'test' => 'testBoolTrue',
                'type' => 'boolean',
                'name' => 'MISP.background_jobs'
            ]
        );
    }
}
