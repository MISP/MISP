<?php

declare(strict_types=1);

use \Helper\Fixture\Data\SightingFixture;
use \Helper\Fixture\Data\EventFixture;
use \Helper\Fixture\Data\UserFixture;
use \Helper\Fixture\Data\AttributeFixture;

class IndexSightingCest
{

    private const URL = '/sightings/index/%s';

    public function testIndexReturnsForbiddenWithoutAuthKey(ApiTester $I): void
    {
        $eventId = 1;
        $I->sendGet(sprintf(self::URL, $eventId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(403);
        $I->seeResponseIsJson();
    }

    public function testIndexReturnsExpectedSighting(ApiTester $I): void
    {
        $orgId = 1;
        $userId = 1;
        $I->haveAuthorizationKey($orgId, $userId, UserFixture::ROLE_ADMIN);

        $eventId = 1;
        $attributeId = 1;
        $fakeEvent = EventFixture::fake(
            [
                'id' => $eventId,
                'org_id' => $orgId,
                'orgc_id' => $orgId
            ]
        );
        $I->haveInDatabase('events', $fakeEvent->toDatabase());
        $fakeAttribute = AttributeFixture::fake(
            [
                'id' => $attributeId,
                'event_id' => (string)$eventId,
                'value1' => 'test value'
            ]
        );
        $I->haveInDatabase('attributes', $fakeAttribute->toDatabase());
        $fakeSighting = SightingFixture::fake(
            [
                'event_id' => $eventId,
                'attribute_id' => $attributeId,
                'org_id' => $orgId
            ]
        );
        $I->haveInDatabase('sightings', $fakeSighting->toDatabase());

        $I->sendGet(sprintf(self::URL, $eventId));

        $I->validateRequest();
        $I->validateResponse();

        $I->seeResponseCodeIs(200);
        $I->seeResponseContainsJson([$fakeSighting->toResponse()]);
    }
}
