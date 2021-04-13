<?php

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;

class ViewAttributesCest
{

    private const URL = '/attributes/view/%d';

    public function testViewReturnsForbiddenWithoutAuthKey(ApiTester $I)
    {
        $attributeId = 10;
        $I->sendGet(sprintf(self::URL, $attributeId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testViewReturnsExpectedAttribute(ApiTester $I)
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
}
