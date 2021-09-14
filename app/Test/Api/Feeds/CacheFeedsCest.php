<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\FeedFixture;

class CacheFeedsCest
{

    private const URL = '/feeds/cacheFeeds/%s';

    public function testCacheFeedsReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendPost(sprintf(self::URL, 'all'));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testCacheFeeds(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);
        $I->haveMispSetting('MISP.background_jobs', '0');

        $feedId = 1;
        $fakeFeed = FeedFixture::fake(
            [
                'id' => (string)$feedId,
                'orgc_id' => (string)$orgId,
                'enabled' => false
            ]
        );
        $I->haveInDatabase('feeds', $fakeFeed->toDatabase());

        $I->sendPost(sprintf(self::URL, 'all'));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'saved' => true,
                'success' => true,
                'name' => 'Caching the feeds has successfully completed.',
                'message' => 'Caching the feeds has successfully completed.',
                'url' => '/feeds/cacheFeed'
            ]
        );
    }
}
