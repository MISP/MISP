<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class RestartDeadWorkersCest
{

    private const URL = '/servers/restartDeadWorkers';

    public function testRestartDeadWorkersReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testRestartDeadWorkers(ApiTester $I): void
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
