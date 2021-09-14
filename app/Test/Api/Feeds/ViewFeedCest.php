<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\FeedFixture;

class ViewFeedCest
{

    private const URL = '/feeds/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $feedId = 1;
        $I->sendGet(sprintf(self::URL, $feedId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedFeed(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $feedId = 1;
        $fakeFeed = FeedFixture::fake(['id' => $feedId, 'orgc_id' => $orgId]);
        $I->haveInDatabase('feeds', $fakeFeed->toDatabase());

        $I->sendGet(sprintf(self::URL, $feedId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Feed' => $fakeFeed->toResponse()]);
    }
}
