<?php

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class AddAttributeCest
{

    private const URL = '/attributes/add/%s';

    public function testAddReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $eventId = 1;

        $fakeAttribute = AttributeFixture::fake(['event_id' => (string)$eventId]);
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
        $eventId = 1;
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $fakeEvent = EventFixture::fake(['id' => (string)$eventId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeAttribute = AttributeFixture::fake(['event_id' => (string)$eventId]);
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
        $I->seeInDatabase('attributes', $fakeAttribute->toDatabase());
    }
}
