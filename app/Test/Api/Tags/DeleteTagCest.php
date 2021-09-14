<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TagFixture;
use \Helper\Fixture\Data\UserFixture;

class DeleteTagCest
{

    private const URL = '/tags/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $tagId = 1;
        $I->sendPost(sprintf(self::URL, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDelete(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $tagId = 1;
        $fakeTag = TagFixture::fake(['id' => $tagId]);
        $I->haveInDatabase('tags', $fakeTag->toDatabase());

        $I->sendPost(sprintf(self::URL, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'name' => 'Tag deleted.',
                'message' => 'Tag deleted.'
            ]
        );
        $I->cantSeeInDatabase('tags', ['id' => $tagId]);
    }
}
