<?php

declare(strict_types=1);

use \Helper\Fixture\Data\WarninglistFixture;
use \Helper\Fixture\Data\UserFixture;
use \Codeception\Scenario;

class ToggleEnableWarninglistCest
{

    private const URL = '/warninglists/toggleEnable';

    public function testToggleEnableReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->haveHttpHeader('Content-Type', 'application/x-www-form-urlencoded');
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testToggleEnable(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Warninglists under change, tests currently broken.');
        $orgId = 1;
        $userId = 1;
        $warninglistId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeWarninglist = WarninglistFixture::fake(
            [
                'id' => $warninglistId,
                'enabled' => false
            ]
        );
        $I->haveInDatabase('warninglists', $fakeWarninglist->toDatabase());

        $I->haveHttpHeader('Content-Type', 'application/x-www-form-urlencoded');
        $I->sendPost(self::URL, ['id' => $warninglistId]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => '1 warninglist(s) enabled'
            ]
        );
        $I->seeInDatabase('warninglists', ['id' => $warninglistId, 'enabled' => true]);
    }

    public function testToggleEnableDisable(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Warninglists under change, tests currently broken.');
        $orgId = 1;
        $userId = 1;
        $warninglistId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeWarninglist = WarninglistFixture::fake(
            [
                'id' => $warninglistId,
                'enabled' => true
            ]
        );
        $I->haveInDatabase('warninglists', $fakeWarninglist->toDatabase());

        $I->haveHttpHeader('Content-Type', 'application/x-www-form-urlencoded');
        $I->sendPost(self::URL, ['id' => $warninglistId]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => '1 warninglist(s) disabled'
            ]
        );
        $I->seeInDatabase('warninglists', ['id' => $warninglistId, 'enabled' => false]);
    }
}
