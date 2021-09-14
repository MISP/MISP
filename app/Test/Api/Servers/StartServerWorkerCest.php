<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;

class StartServerWorkerCest
{

    private const URL = '/servers/startWorker/%s';

    public function testStartServerWorkerReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $worker = 'email';
        $I->sendPost(sprintf(self::URL, $worker));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testStartServerWorker(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $worker = 'email';
        $I->sendPost(sprintf(self::URL, $worker));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => "Worker start signal sent",
                'message' => "Worker start signal sent",
                'url' => sprintf(self::URL, $worker),
            ]
        );
    }
}
