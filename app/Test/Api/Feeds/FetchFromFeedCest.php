<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\FeedFixture;
use \WireMock\Client\WireMock;

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
        $I->haveMispSetting('MISP.background_jobs', '0');

        $feedId = 1;
        $fakeFeed = FeedFixture::fake(
            [
                'id' => (string)$feedId,
                'orgc_id' => (string)$orgId,
                'enabled' => true,
                'url' => 'http://wiremock:8080/fetch-feed',
                'source_format' => 'misp'
            ]
        );
        $I->haveInDatabase('feeds', $fakeFeed->toDatabase());

        $I->getWireMock()->stubFor(WireMock::get(WireMock::urlEqualTo('/fetch-feed/manifest.json'))
            ->willReturn(WireMock::aResponse()
                ->withHeader('Content-Type', 'application/json')
                ->withBody('{}')));

        $I->sendPost(sprintf(self::URL, $feedId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'result' => 'Fetching the feed has successfully completed.'
            ]
        );
    }
}
