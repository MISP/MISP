<?php

declare(strict_types=1);

use \Helper\Fixture\Data\WarninglistFixture;
use \Helper\Fixture\Data\UserFixture;
use \Codeception\Scenario;

class ViewWarninglistCest
{

    private const URL = '/warninglists/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $warninglistId = 1;
        $I->sendGet(sprintf(self::URL, $warninglistId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewIndexReturnsExpectedWarninglist(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Warninglists under change, tests currently broken.');
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $warninglistId = 1;
        $fakeWarninglist = WarninglistFixture::fake(['id' => $warninglistId]);
        $I->haveInDatabase('warninglists', $fakeWarninglist->toDatabase());

        $I->sendGet(sprintf(self::URL, $warninglistId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Warninglist' => $fakeWarninglist->toResponse()]);
    }
}
