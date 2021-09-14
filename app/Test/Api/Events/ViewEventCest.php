<?php

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class ViewEventCest
{

    private const URL = '/events/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $eventId = 1;
        $I->sendGet(sprintf(self::URL, $eventId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedEvent(ApiTester $I): void
    {
        $orgId = 1;
        $eventId = 1;

        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);
        $fakeEvent = EventFixture::fake(
            [
                'id' => (string)$eventId,
                'org_id' => (string)$orgId,
                'orgc_id' => (string)$orgId
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $I->sendGet(sprintf(self::URL, $eventId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Event' => $fakeEvent->toResponse()]);
    }
}
