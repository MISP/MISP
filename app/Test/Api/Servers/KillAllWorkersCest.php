<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class KillAllWorkersCest
{

    private const URL = '/servers/killAllWorkers';

    public function testKillAllWorkersReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testKillAllWorkers(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => "Killing workers.",
                'message' => "Killing workers.",
                'url' => self::URL
            ]
        );
    }
}
