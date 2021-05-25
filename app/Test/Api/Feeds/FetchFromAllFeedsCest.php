<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\FeedFixture;

class FetchFromAllFeedsCest
{

    private const URL = '/feeds/fetchFromAllFeeds';

    public function testFetchFromAllFeedsReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testFetchFromAllFeeds(ApiTester $I): void
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

        $I->sendPost(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'result' => 'Pull queued for background execution.'
            ]
        );
        // TODO: fetch from all feeds job created in Redis
    }
}
