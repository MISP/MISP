<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class UpdateServerCest
{

    private const URL = '/servers/update';

    public function testUpdateReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testUpdate(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        // TODO: check update went ok, now returns: "Update failed, you are not on branch"
    }
}
