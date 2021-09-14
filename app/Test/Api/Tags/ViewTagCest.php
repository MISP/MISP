<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TagFixture;
use \Helper\Fixture\Data\UserFixture;

class ViewTagCest
{

    private const URL = '/tags/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $tagId = 1;
        $I->sendGet(sprintf(self::URL, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedTag(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $tagId = 1;
        $fakeTag = TagFixture::fake(['id' => $tagId]);
        $I->haveInDatabase('tags', $fakeTag->toDatabase());

        $I->sendGet(sprintf(self::URL, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson($fakeTag->toResponse());
    }
}
