<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\FeedFixture;

class AddFeedCest
{

    private const URL = '/feeds/add';

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

        $feedId = 1;
        $fakeFeed = FeedFixture::fake(
            [
                (string)'id' => $feedId,
                'orgc_id' => (string)$orgId
            ]
        );

        $I->sendPost(self::URL, $fakeFeed->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $fakeFeed->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..Feed.id')[0]
        ]);

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Feed' => $fakeFeed->toResponse()]);
        $I->seeInDatabase('feeds', $fakeFeed->toDatabase());
    }
}
