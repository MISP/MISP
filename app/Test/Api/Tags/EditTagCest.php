<?php

declare(strict_types=1);

use \Helper\Fixture\Data\TagFixture;
use \Helper\Fixture\Data\UserFixture;

class EditTagCest
{

    private const URL = '/tags/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $tagId = 1;
        $I->sendPost(sprintf(self::URL, $tagId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEdit(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $tagId = 1;
        $fakeTag = TagFixture::fake(['id' => $tagId, 'name' => 'foo']);
        $I->haveInDatabase('tags', $fakeTag->toDatabase());

        $fakeTag->set(['name' => 'bar']);

        $I->sendPost(sprintf(self::URL, $tagId), $fakeTag->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Tag' => $fakeTag->toResponse()]);
    }
}
