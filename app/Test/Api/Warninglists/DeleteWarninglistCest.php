<?php

declare(strict_types=1);

use \Helper\Fixture\Data\WarninglistFixture;
use \Helper\Fixture\Data\UserFixture;

class DeleteWarninglistCest
{

    private const URL = '/warninglists/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $warninglistId = 1;
        $I->sendPost(sprintf(self::URL, $warninglistId));

        // $I->validateRequest();
        // $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDelete(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $warninglistId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeWarninglist = WarninglistFixture::fake(['id' => $warninglistId]);
        $I->haveInDatabase('warninglists', $fakeWarninglist->toDatabase());

        $I->sendPost(sprintf(self::URL, $warninglistId));

        // $I->validateRequest();
        // $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([]);
        $I->cantSeeInDatabase('warninglists', ['id' => $warninglistId]);
    }
}
