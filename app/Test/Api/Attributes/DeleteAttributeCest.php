<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;

class DeleteAttributeCest
{

    private const URL = '/attributes/delete/%s';

    public function testDeleteReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $eventId = 1;
        $attributeId = 1;

        $fakeAttribute = AttributeFixture::fake(['id' => (string)$attributeId, 'event_id' => (string)$eventId]);
        $I->sendDelete(sprintf(self::URL, $attributeId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testDeleteByIDRemovesAttribute(ApiTester $I): void
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

        $I->sendDelete(sprintf(self::URL, $attributeId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['message' => 'Attribute deleted.']);
        $I->seeInDatabase('attributes', ['id' => $attributeId, 'deleted' => 1]);
    }

    public function testDeleteByUUIDRemovesAttribute(ApiTester $I): void
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

        $I->sendDelete(sprintf(self::URL, $attributeUUID));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['message' => 'Attribute deleted.']);
        $I->seeInDatabase('attributes', ['uuid' => $attributeUUID, 'deleted' => 1]);
    }
}
