<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TagFixture;
use \Helper\Fixture\Data\UserFixture;

class ViewTagCest
{

    private const URL = '/tags/add';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAdd(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $tagId = 1;
        $fakeTag = TagFixture::fake();

        $I->sendPost(self::URL, $fakeTag->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $fakeTag->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..id')[0],
        ]);

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson($fakeTag->toResponse());
        $I->seeInDatabase('tags', $fakeTag->toDatabase());
    }
}
