<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TagFixture;
use \Helper\Fixture\Data\UserFixture;

class IndexTagsCest
{

    private const URL = '/tags';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedTag(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $fakeTag = TagFixture::fake();
        $I->haveInDatabase('tags', $fakeTag->toDatabase());

        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Tag' => [$fakeTag->toResponse()]]);
    }
}
