<?php

declare(strict_types=1);

use \Helper\Fixture\Data\WarninglistFixture;
use \Helper\Fixture\Data\UserFixture;
use \Codeception\Scenario;

class CheckWarninglistValueCest
{

    private const URL = '/warninglists/checkValue';

    public function testCheckValueReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testCheckValueWhenWarninglistIsEnabled(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Warninglists under change, tests currently broken.');
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->sendCommandToRedis('flushall');

        $warninglistId = 1;
        $warninglistName = 'test warninglist';
        $value = '10.128.0.0';
        $fakeWarninglist = WarninglistFixture::fake(
            [
                'id' => $warninglistId,
                'name' => $warninglistName,
                'type' => 'cidr',
                'enabled' => true
            ]
        );

        $I->haveInDatabase('warninglists', $fakeWarninglist->toDatabase());
        $I->haveInDatabase(
            'warninglist_types',
            [
                'type' => 'cidr',
                'warninglist_id' => $warninglistId
            ]
        );
        $I->haveInDatabase(
            'warninglist_entries',
            [
                'value' => $value,
                'warninglist_id' => $warninglistId
            ]
        );

        $I->sendPost(self::URL, [$value]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                $value => [
                    'id' => $warninglistId,
                    'name' => $warninglistName,
                ]
            ]
        );
    }
}
