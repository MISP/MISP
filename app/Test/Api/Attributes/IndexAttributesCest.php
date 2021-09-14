<?php

declare(strict_types=1);

use \Helper\Fixture\Data\AttributeFixture;
use \Helper\Fixture\Data\EventFixture;

class IndexAttributesCest
{

    private const URL = '/attributes';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedAttribute(ApiTester $I): void
    {
        $eventId = 1;
        $orgId = 1;
        $userId = 1;

        $I->haveAuthorizationKey($orgId, $userId);
        $fakeEvent = EventFixture::fake(['id' => $eventId, 'org_id' => $orgId, 'user_id' => $userId]);
        $I->haveInDatabase('events', $fakeEvent->toDatabase());

        $fakeAttribute = AttributeFixture::fake(['event_id' => $eventId]);
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());
        $I->sendGet(self::URL);

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson($fakeAttribute->toResponse());
    }
}
