<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Codeception\Scenario;

class UpdateWarninglistCest
{

    private const URL = '/warninglists/update';

    public function testUpdateReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testUpdate(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('/warninglists/updates takes too long.');
        $orgId = 1;
        $userId = 1;
        $warninglistId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $I->sendPost(self::URL, ['id' => $warninglistId]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'url' => "/warninglists/update",
            ]
        );
        $I->seeResponseMatchesJsonType([
            'message' => 'string:regex(/^Successfully updated \d+ warninglists.$/)'
        ]);
    }
}
