<?php

declare(strict_types=1);

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class AddEventCest
{

    private const URL = '/events/add';

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

        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);

        $fakeEvent = EventFixture::fake(['org_id' => (string)$orgId]);

        $I->sendPost(self::URL, $fakeEvent->toRequest());

        // $I->validateRequest();
        $I->validateResponse();

        $fakeEvent->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..Event.id')[0],
            'timestamp' => $I->grabDataFromResponseByJsonPath('$..Event.timestamp')[0],
        ]);

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Event' => $fakeEvent->toResponse()]);
        $I->seeInDatabase('events', $fakeEvent->toDatabase());
    }
}
