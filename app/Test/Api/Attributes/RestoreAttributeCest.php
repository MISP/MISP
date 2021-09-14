<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Codeception\Scenario;

class RestoreAttributeCest
{

    private const URL = '/attributes/restore/%s';

    public function testRestoreReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $eventId = 1;
        $attributeId = 1;

        $fakeAttribute = AttributeFixture::fake(['id' => (string)$attributeId, 'event_id' => (string)$eventId]);
        $I->sendPost(sprintf(self::URL, $attributeId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testRestoreByIDRestoresAttribute(ApiTester $I): void
    {
        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $attributeId = 10;
        $fakeEvent = EventFixture::fake(['id' => (string)$eventId]);
        $fakeAttribute = AttributeFixture::fake(
            [
                'id' => (string)$attributeId,
                'event_id' => (string)$eventId,
                'type' => 'text',
                'timestamp' => '0',
                'deleted' => 1
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->sendPost(sprintf(self::URL, $attributeId));

        $fakeAttribute->set([
            'deleted' => false,
            'timestamp' => $I->grabDataFromResponseByJsonPath('$..Attribute.timestamp')[0]
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Attribute' => $fakeAttribute->toResponse()]);
        $I->seeInDatabase('attributes', ['id' => $attributeId, 'deleted' => 0]);
    }

    public function testRestoreByUUIDRestoresAttribute(ApiTester $I, Scenario $scenario): void
    {
        $scenario->skip('Endpoint not available, TODO: Enable restore attribute by UUID');

        $I->haveAuthorizationKey(1, 1, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $attributeUUID = '574e881d-07c0-4197-8d83-4e35950d210f';
        $fakeEvent = EventFixture::fake(['id' => (string)$eventId]);
        $fakeAttribute = AttributeFixture::fake(
            [
                'uuid' => $attributeUUID,
                'event_id' => (string)$eventId,
                'type' => 'text',
                'timestamp' => '0',
                'deleted' => 1
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->sendPost(sprintf(self::URL, $attributeUUID));

        $fakeAttribute->set([
            'deleted' => false,
            'timestamp' => $I->grabDataFromResponseByJsonPath('$..Attribute.timestamp')[0]
        ]);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson(['Attribute' => $fakeAttribute->toResponse()]);
        $I->seeInDatabase('attributes', ['id' => $attributeUUID, 'deleted' => 0]);
    }
}
