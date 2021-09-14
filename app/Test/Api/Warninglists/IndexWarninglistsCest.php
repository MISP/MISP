<?php

declare(strict_types=1);

use \Helper\Fixture\Data\WarninglistFixture;
use \Helper\Fixture\Data\UserFixture;
use \Codeception\Scenario;

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

    public function testIndexReturnsExpectedWarninglist(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Warninglists under change, tests currently broken.');
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

    public function testPostIndexReturnsExpectedWarninglist(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Warninglists under change, tests currently broken.');
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeWarninglistFoo = WarninglistFixture::fake(['name' => 'foo']);
        $fakeWarninglistBar = WarninglistFixture::fake(['name' => 'bar']);
        $I->haveInDatabase('warninglists', $fakeWarninglistFoo->toDatabase());
        $I->haveInDatabase('warninglists', $fakeWarninglistBar->toDatabase());

        $I->haveHttpHeader('Content-Type', 'application/x-www-form-urlencoded');
        $I->sendPost(self::URL, ['value' => 'foo']);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'Warninglists' => [
                    'Warninglist' => $fakeWarninglistFoo->toResponse()
                ]
            ]
        );
    }
}
