<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class RestartWorkersCest
{

    private const URL = '/servers/restartWorkers';

    public function testRestartWorkersReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testRestartWorkers(ApiTester $I): void
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
                'name' => "Restarting workers.",
                'message' => "Restarting workers.",
                'url' => self::URL
            ]
        );
    }
}
