<?php

declare(strict_types=1);

use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class EditEventCest
{

    private const URL = '/events/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $eventId = 1;
        $I->sendPut(sprintf(self::URL, $eventId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEdit(ApiTester $I): void
    {
        $orgId = 1;
        $eventId = 1;

        $I->haveAuthorizationKey($orgId, 1, UserFixture::ROLE_ADMIN);
        $fakeEvent = EventFixture::fake(
            [
                'id' => (string)$eventId,
                'org_id' => (string)$orgId,
                'orgc_id' => (string)$orgId,
                'threat_level_id' => '1'
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeEvent->set(
            [
                'threat_level_id' => '3',
                'timestamp' => null
            ]
        );

        $I->sendPut(sprintf(self::URL, $eventId), $fakeEvent->toRequest());

        $I->validateRequest();
        $I->validateResponse();

        $fakeEvent->set([
            'timestamp' => $I->grabDataFromResponseByJsonPath('$..Event.timestamp')[0],
        ]);

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Event' => $fakeEvent->toResponse()]);
        $I->seeInDatabase('events', $fakeEvent->toDatabase());
    }
}
