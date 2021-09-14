<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class StopServerWorkerCest
{

    private const URL = '/servers/stopWorker/%s';

    public function testStopServerWorkerReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $workerPid = 123;
        $I->sendPost(sprintf(self::URL, $workerPid));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testStopServerWorker(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $workerPid = 1234;
        $I->sendPost(sprintf(self::URL, $workerPid));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => "Worker stop signal sent",
                'message' => "Worker stop signal sent",
                'url' => sprintf(self::URL, $workerPid),
            ]
        );
    }
}
