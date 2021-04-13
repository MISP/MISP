<?php

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class EditAttributeCest
{

    private const URL = '/attributes/edit/%d';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $eventId = '1';
        $attributeId = '1';

        $fakeAttribute = AttributeFixture::fake(['id' => $attributeId, 'event_id' => $eventId]);
        $I->sendPut(
            sprintf(self::URL, $attributeId),
            $fakeAttribute->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEditModifiesExpectedAttribute(ApiTester $I)
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $eventId = '1';
        $attributeId = '10';
        $fakeEvent = EventFixture::fake(['id' => $eventId]);
        $fakeAttribute = AttributeFixture::fake(
            [
                'id' => $attributeId,
                'event_id' => $eventId,
                'type' => 'text',
                'timestamp' => '0'
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $fakeAttribute->set([
            'value1' => 'foobar',
            'timestamp' => null
        ]);

        $I->sendPut(
            sprintf(self::URL, $attributeId),
            $fakeAttribute->toRequest()
        );

        $fakeAttribute->set([
            'timestamp' => $I->grabDataFromResponseByJsonPath('$..Attribute.timestamp')[0],
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(
            [
                'Attribute' => $fakeAttribute->toResponse(),
            ]
        );
        $I->seeInDatabase('attributes', $fakeAttribute->toDatabase());
    }
}
