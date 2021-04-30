<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;

class ViewAttributesCest
{

    private const URL = '/attributes/view/%s';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $attributeId = 10;
        $I->sendGet(sprintf(self::URL, $attributeId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewByIDReturnsExpectedAttribute(ApiTester $I)
    {
        $attributeId = 10;
        $eventId = 1;
        $orgId = 10;
        $userId = 10;

        $I->haveAuthorizationKey($orgId, $userId);
        $fakeEvent = EventFixture::fake(['id' => $eventId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeAttribute = AttributeFixture::fake(['id' => $attributeId, 'event_id' => $eventId]);
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->sendGet(sprintf(self::URL, $attributeId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson($fakeAttribute->toResponse());
    }

    public function testViewByUUIDReturnsExpectedAttribute(ApiTester $I)
    {
        $attributeUUID = '574e881d-07c0-4197-8d83-4e35950d210f';
        $eventId = 1;
        $orgId = 1;
        $userId = 1;

        $I->haveAuthorizationKey($orgId, $userId);
        $fakeEvent = EventFixture::fake(['id' => $eventId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeAttribute = AttributeFixture::fake(['uuid' => $attributeUUID, 'event_id' => $eventId]);
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());

        $I->sendGet(sprintf(self::URL, $attributeUUID));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson($fakeAttribute->toResponse());
    }
}
