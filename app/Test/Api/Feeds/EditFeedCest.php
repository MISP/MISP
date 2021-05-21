<?php

declare(strict_types=1);

use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\FeedFixture;

class EditFeedCest
{

    private const URL = '/feeds/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $feedId = 1;
        $I->sendPut(sprintf(self::URL, $feedId));

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

        $feedId = 1;
        $fakeFeed = FeedFixture::fake(
            [
                'id' => (string)$feedId,
                'orgc_id' => (string)$orgId
            ]
        );
        $I->haveInDatabase('feeds', $fakeFeed->toDatabase());

        $fakeFeed->set(
            [
                'url' => 'https://www.foobar.local',
                'rules' => json_encode(
                    [
                        'tags' =>
                        [
                            'NOT' => ['tlp:white']
                        ]
                    ]
                )
            ]
        );

        $I->sendPut(sprintf(self::URL, $feedId), $fakeFeed->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Feed' => $fakeFeed->toResponse()]);
    }
}
