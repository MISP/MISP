<?php

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class DeleteEventCest
{

    private const URL = '/events/delete/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $eventId = 1;
        $I->sendDelete(sprintf(self::URL, $eventId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedEvent(ApiTester $I)
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

        $I->sendDelete(sprintf(self::URL, $eventId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([
            'saved' => true,
            'success' => true,
            'name' => 'Event deleted.',
            'message' => 'Event deleted.',
            'url' => sprintf('/events/delete/%s', $eventId),
        ]);
        $I->cantSeeInDatabase('events', ['id' => $eventId]);
    }
}
