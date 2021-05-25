<?php

declare(strict_types=1);

use \Helper\Fixture\Data\WarninglistFixture;
use \Helper\Fixture\Data\UserFixture;

class IndexWarninglistsCest
{

    private const URL = '/warninglists';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedWarninglist(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeWarninglist = WarninglistFixture::fake();
        $I->haveInDatabase('warninglists', $fakeWarninglist->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'Warninglists' => [
                    'Warninglist' => $fakeWarninglist->toResponse()
                ]
            ]
        );
    }
}
