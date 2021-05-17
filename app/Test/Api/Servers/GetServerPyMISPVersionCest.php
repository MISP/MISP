<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class GetServerPyMISPVersionCest
{

    private const URL = '/servers/getPyMISPVersion';

    public function testGetPyMISPVersionReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testGetPyMISMPVersion(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);

        $I->seeResponseMatchesJsonType([
            'version' => 'string:regex(/^\d+\.\d+.\d+$/)'
        ]);
    }
}
