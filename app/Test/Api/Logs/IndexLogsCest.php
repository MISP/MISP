<?php

declare(strict_types=1);

use \Helper\Fixture\Data\LogFixture;
use \Helper\Fixture\Data\UserFixture;

class IndexLogsCest
{

    private const URL = '/admin/logs';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedLog(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeLog1 = LogFixture::fake(['action' => 'add', 'model' => 'Attribute']);
        $fakeLog2 = LogFixture::fake(['action' => 'delete', 'model' => 'Attribute']);
        $I->haveInDatabase('logs', $fakeLog1->toDatabase());
        $I->haveInDatabase('logs', $fakeLog2->toDatabase());

        $I->sendPost(
            self::URL,
            [
                'action' => 'delete'
            ]
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                [
                    'Log' => $fakeLog2->toResponse()
                ]
            ]
        );
    }
}
