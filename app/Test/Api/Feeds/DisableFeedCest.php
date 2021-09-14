<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\FeedFixture;

class DisableFeedCest
{

    private const URL = '/feeds/disable/%s';

    public function testDisableFeedReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $feedId = 1;
        $I->sendPost(sprintf(self::URL, $feedId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDisableFeed(ApiTester $I): void
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

        $I->sendPost(sprintf(self::URL, $feedId), $fakeFeed->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'name' => 'Feed disabled.',
                'message' => 'Feed disabled.',
                'url' => sprintf(self::URL, $feedId)
            ]
        );
        $I->seeInDatabase('feeds', ['id' => $feedId, 'enabled' => false]);
    }
}
