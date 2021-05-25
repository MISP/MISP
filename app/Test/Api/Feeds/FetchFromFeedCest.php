<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\FeedFixture;

class FetchFromFeedCest
{

    private const URL = '/feeds/fetchFromFeed/%s';

    public function testFetchFromFeedReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $feedId = 1;
        $I->sendPost(sprintf(self::URL, $feedId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testFetchFromFeed(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $feedId = 1;
        $fakeFeed = FeedFixture::fake(
            [
                'id' => (string)$feedId,
                'orgc_id' => (string)$orgId,
                'enabled' => true
            ]
        );
        $I->haveInDatabase('feeds', $fakeFeed->toDatabase());

        $I->sendPost(sprintf(self::URL, $feedId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'result' => 'Pull queued for background execution.'
            ]
        );
        // TODO: fetch feed job created in Redis
    }
}
