<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TagFixture;
use \Helper\Fixture\Data\UserFixture;

class SearchTagsCest
{

    private const URL = '/tags/search/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $searchTerm = '%tlp%';
        $I->sendGet(sprintf(self::URL, $searchTerm));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testSearchReturnsExpectedTag(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $tagId = 1;
        $searchTerm = '%tlp%';
        $fakeTag = TagFixture::fake(['id' => $tagId, 'name' => 'tlp:white']);
        $I->haveInDatabase('tags', $fakeTag->toDatabase());

        $I->sendGet(sprintf(self::URL, $searchTerm));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Tag' => $fakeTag->toResponse()]);
    }
}
