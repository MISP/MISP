<?php

use \Helper\Fixture\AttributeFixture;
use \Helper\Fixture\EventFixture;

class AddAttributeCest
{

    private const URL = '/attributes/add/%d';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $eventId = '1';

        $fakeAttribute = AttributeFixture::fake(['event_id' => $eventId]);
        $I->sendPost(
            sprintf(self::URL, $eventId),
            $fakeAttribute->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testAddCreatesExpectedAttribute(ApiTester $I)
    {
        $I->haveAdminAuthorizationKey();

        $eventId = '1';
        $fakeEvent = EventFixture::fake(['id' => $eventId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeAttribute = AttributeFixture::fake(['event_id' => $eventId]);
        $I->sendPost(
            sprintf(self::URL, $eventId),
            $fakeAttribute->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $fakeAttribute->set([
            'id' => $I->grabDataFromResponseByJsonPath('$..Attribute.id')[0],
            'timestamp' => $I->grabDataFromResponseByJsonPath('$..Attribute.timestamp')[0],
        ]);

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'Attribute' => $fakeAttribute->toResponse(),
                'AttributeTag' => []
            ]
        );
    }
}
