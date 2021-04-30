<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class EditAttributeCest
{

    private const URL = '/attributes/edit/%s';

    public function testEditReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $eventId = 1;
        $attributeId = 1;

        $fakeAttribute = AttributeFixture::fake(['id' => (string)$attributeId, 'event_id' => (string)$eventId]);
        $I->sendPut(
            sprintf(self::URL, $attributeId),
            $fakeAttribute->toRequest()
        );

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testEditByIDModifiesExpectedAttribute(ApiTester $I)
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $attributeId = 1;
        $fakeEvent = EventFixture::fake(['id' => (string)$eventId]);
        $fakeAttribute = AttributeFixture::fake(
            [
                'id' => (string)$attributeId,
                'event_id' => (string)$eventId,
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

    public function testEditByUUIDModifiesExpectedAttribute(ApiTester $I)
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $attributeUUID = '574e881d-07c0-4197-8d83-4e35950d210f';
        $fakeEvent = EventFixture::fake(['id' => (string)$eventId]);
        $fakeAttribute = AttributeFixture::fake(
            [
                'uuid' => $attributeUUID,
                'event_id' => (string)$eventId,
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
            sprintf(self::URL, $attributeUUID),
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
